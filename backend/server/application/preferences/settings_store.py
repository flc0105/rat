import json
import threading
import time


class SettingsStore:
    """Small JSON-valued namespaces persisted in the shared rch.db settings table."""

    def __init__(self, database, namespace: str):
        self.database = database
        self.namespace = str(namespace or '').strip()
        if not self.namespace:
            raise ValueError('settings namespace is required')
        self._lock = threading.RLock()

    def read(self) -> dict:
        with self._lock:
            row = self.database.connection().execute(
                'SELECT value_json FROM settings WHERE namespace = ?',
                (self.namespace,),
            ).fetchone()
            if row is None:
                return {}
            try:
                payload = json.loads(row['value_json'] or '{}')
                return payload if isinstance(payload, dict) else {}
            except Exception:
                return {}

    def write(self, payload: dict):
        value = payload if isinstance(payload, dict) else {}
        encoded = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
        with self._lock:
            self.database.connection().execute(
                '''
                INSERT INTO settings(namespace, value_json, updated_at_ms)
                VALUES (?, ?, ?)
                ON CONFLICT(namespace) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at_ms = excluded.updated_at_ms
                ''',
                (self.namespace, encoded, int(time.time() * 1000)),
            )
