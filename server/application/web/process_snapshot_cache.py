import threading
import time


class ProcessSnapshotCache:
    """
    进程/应用快照缓存。

    职责：
    - 为 process/app 列表提供短时缓存
    - 记录是否正在后台刷新，避免重复刷新
    - 支持 kill 后失效，避免继续展示过期列表
    """

    def __init__(self, default_ttl_seconds: float = 8.0, app_ttl_seconds: float = 12.0):
        self.default_ttl_seconds = float(default_ttl_seconds)
        self.app_ttl_seconds = float(app_ttl_seconds)
        self._lock = threading.RLock()
        self._entries = {}

    def _build_slot_key(self, target_key: str, snapshot_type: str) -> str:
        return f'{target_key}::{snapshot_type}'

    def _resolve_ttl(self, snapshot_type: str, ttl_seconds=None) -> float:
        if ttl_seconds is not None:
            return max(0.0, float(ttl_seconds))
        if snapshot_type == 'apps':
            return self.app_ttl_seconds
        return self.default_ttl_seconds

    def get_snapshot(self, target_key: str, snapshot_type: str, *, ttl_seconds=None) -> dict:
        now = time.time()
        slot_key = self._build_slot_key(target_key, snapshot_type)
        ttl_value = self._resolve_ttl(snapshot_type, ttl_seconds=ttl_seconds)

        with self._lock:
            entry = self._entries.get(slot_key)
            if not entry:
                return {
                    'has_data': False,
                    'data': None,
                    'updated_at': 0.0,
                    'refreshing': False,
                    'is_stale': True,
                    'age_seconds': 0.0,
                    'ttl_seconds': ttl_value,
                }

            updated_at = float(entry.get('updated_at') or 0.0)
            age_seconds = max(0.0, now - updated_at) if updated_at else 0.0
            data = entry.get('data')
            has_data = updated_at > 0.0
            is_stale = (not has_data) or age_seconds >= ttl_value

            return {
                'has_data': has_data,
                'data': data,
                'updated_at': updated_at,
                'refreshing': bool(entry.get('refreshing')),
                'is_stale': is_stale,
                'age_seconds': age_seconds,
                'ttl_seconds': ttl_value,
            }

    def store_snapshot(self, target_key: str, snapshot_type: str, data) -> None:
        slot_key = self._build_slot_key(target_key, snapshot_type)
        with self._lock:
            entry = self._entries.setdefault(slot_key, {})
            entry['data'] = data
            entry['updated_at'] = time.time()
            entry['refreshing'] = False

    def begin_refresh(self, target_key: str, snapshot_type: str) -> bool:
        slot_key = self._build_slot_key(target_key, snapshot_type)
        with self._lock:
            entry = self._entries.setdefault(slot_key, {
                'data': None,
                'updated_at': 0.0,
                'refreshing': False,
            })
            if entry.get('refreshing'):
                return False
            entry['refreshing'] = True
            return True

    def end_refresh(self, target_key: str, snapshot_type: str) -> None:
        slot_key = self._build_slot_key(target_key, snapshot_type)
        with self._lock:
            entry = self._entries.get(slot_key)
            if not entry:
                return
            entry['refreshing'] = False

    def invalidate(self, target_key: str, snapshot_type: str = '') -> None:
        with self._lock:
            if snapshot_type:
                self._entries.pop(self._build_slot_key(target_key, snapshot_type), None)
                return

            prefix = f'{target_key}::'
            to_delete = [key for key in self._entries.keys() if key.startswith(prefix)]
            for key in to_delete:
                self._entries.pop(key, None)