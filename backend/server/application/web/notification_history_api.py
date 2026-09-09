class WebNotificationHistoryApi:
    """SSE 通知中心 Web 子外观。"""

    def __init__(self, history_store, event_bus=None):
        self.history_store = history_store
        self.event_bus = event_bus

    def get_history(self):
        return self.history_store.get_history()

    def add_notification(self, payload: dict):
        notification, created = self.history_store.add_notification(payload or {})
        if created and self.event_bus is not None:
            self.event_bus.publish('notification_center_updated', {
                'action': 'added',
                'notification': notification,
            })
        return notification

    def delete_notification(self, notification_id: str):
        deleted = self.history_store.delete_notification(notification_id)
        if deleted and self.event_bus is not None:
            self.event_bus.publish('notification_center_updated', {
                'action': 'deleted',
                'id': str(notification_id or '').strip(),
            })
        return {'deleted': deleted}

    def clear_history(self):
        removed_count = self.history_store.clear_history()
        if self.event_bus is not None:
            self.event_bus.publish('notification_center_updated', {
                'action': 'cleared',
                'removed_count': removed_count,
            })
        return {'removed_count': removed_count}

    def cleanup_before_epoch(self, cutoff_epoch: float):
        result = self.history_store.cleanup_before_epoch(cutoff_epoch)
        removed = result.get('removed') if isinstance(result, dict) else []
        removed = removed if isinstance(removed, list) else []
        removed_ids = [
            str(item.get('id') or '').strip()
            for item in removed
            if str(item.get('id') or '').strip()
        ]
        if removed_ids and self.event_bus is not None:
            self.event_bus.publish('notification_center_updated', {
                'action': 'pruned',
                'ids': removed_ids,
            })
        return result
