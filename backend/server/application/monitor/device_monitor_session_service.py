import threading
import time
import uuid
from datetime import datetime

from core.protocol.message_types import (
    MSG_TYPE_MONITOR_CLOSE,
    MSG_TYPE_MONITOR_CONFIG,
    MSG_TYPE_MONITOR_OPEN,
)


class DeviceMonitorSessionService:
    """
    Server 端轻量设备监控会话。

    第一版按当前浏览器 Tab 定向转发监控 SSE，不参与 foreground command。
    channel 模型保留 config 能力，后续 Processes / Services 可以复用同一会话协议。
    """

    SUPPORTED_CHANNELS = {'system', 'storage', 'network', 'battery'}
    DEFAULT_INTERVALS = {
        'system': 0.5,
        'network': 0.5,
        'storage': 5.0,
        'battery': 5.0,
    }
    MIN_INTERVAL_SECONDS = 0.25
    MAX_INTERVAL_SECONDS = 60.0

    def __init__(self, server, event_bus):
        self.server = server
        self.event_bus = event_bus
        self._lock = threading.RLock()
        self._sessions = {}

    def create_session(self, client_id: str, tab_id: str, channels=None, intervals=None) -> dict:
        client_id = str(client_id or '').strip()
        tab_id = str(tab_id or '').strip()
        if not tab_id:
            raise ValueError('X-Tab-Id is required for device monitor')

        session = self.server.get_target_connection_by_client_id(client_id)
        self._close_existing_tab_sessions(tab_id)

        monitor_session_id = str(uuid.uuid4())
        normalized_channels = self._normalize_channels(channels)
        normalized_intervals = self._normalize_intervals(intervals, normalized_channels)
        item = {
            'monitor_session_id': monitor_session_id,
            'client_id': client_id,
            'tab_id': tab_id,
            'status': 'opening',
            'channels': normalized_channels,
            'intervals': normalized_intervals,
            'created_at': time.time(),
            'opened_at': 0.0,
            'closed_at': 0.0,
            'last_snapshot_at': 0.0,
            'error': '',
        }

        with self._lock:
            self._sessions[monitor_session_id] = item

        try:
            session.send({
                'type': MSG_TYPE_MONITOR_OPEN,
                'monitor_session_id': monitor_session_id,
                'channels': normalized_channels,
                'intervals': normalized_intervals,
            })
        except Exception:
            with self._lock:
                self._sessions.pop(monitor_session_id, None)
            raise

        return self._serialize(item)

    def update_session(self, monitor_session_id: str, tab_id: str, channels=None, intervals=None) -> dict:
        item = self._get_required_for_tab(monitor_session_id, tab_id)
        with self._lock:
            next_channels = self._normalize_channels(item['channels'] if channels is None else channels)
            next_intervals = self._normalize_intervals(
                item['intervals'] if intervals is None else intervals,
                next_channels,
            )
            item['channels'] = next_channels
            item['intervals'] = next_intervals

        session = self.server.get_target_connection_by_client_id(item['client_id'])
        session.send({
            'type': MSG_TYPE_MONITOR_CONFIG,
            'monitor_session_id': item['monitor_session_id'],
            'channels': next_channels,
            'intervals': next_intervals,
        })
        return self._serialize(item)

    def close_session(self, monitor_session_id: str, tab_id: str = '') -> dict:
        item = self._get_required_for_tab(monitor_session_id, tab_id) if tab_id else self._get_required(monitor_session_id)
        try:
            session = self.server.get_target_connection_by_client_id(item['client_id'])
            session.send({
                'type': MSG_TYPE_MONITOR_CLOSE,
                'monitor_session_id': item['monitor_session_id'],
            })
        except Exception:
            pass

        with self._lock:
            if item.get('status') not in ('closed', 'error'):
                item['status'] = 'closing'
        return {'ok': True, 'monitor_session_id': item['monitor_session_id']}

    def handle_client_opened(self, monitor_session_id: str, channels=None, intervals=None):
        with self._lock:
            item = self._sessions.get(str(monitor_session_id or ''))
            if not item:
                return
            item['status'] = 'open'
            item['opened_at'] = time.time()
            if isinstance(channels, list):
                item['channels'] = self._normalize_channels(channels)
            if isinstance(intervals, dict):
                item['intervals'] = self._normalize_intervals(intervals, item['channels'])
            event_item = self._serialize(item)

        self._publish_status(event_item, 'open')

    def handle_client_snapshot(self, monitor_session_id: str, seq, channel: str, data, collected_at):
        normalized_id = str(monitor_session_id or '').strip()
        normalized_channel = str(channel or '').strip().lower()
        if normalized_channel not in self.SUPPORTED_CHANNELS:
            return

        with self._lock:
            item = self._sessions.get(normalized_id)
            if not item:
                return
            item['status'] = 'open'
            item['last_snapshot_at'] = time.time()
            payload = {
                'monitor_session_id': item['monitor_session_id'],
                'client_id': item['client_id'],
                'channel': normalized_channel,
                'seq': int(seq or 0),
                'data': data if isinstance(data, dict) else {},
                'collected_at': collected_at or time.time(),
                'time': datetime.now().isoformat(),
            }
            target_tab_id = item['tab_id']

        self.event_bus.publish(
            'device_monitor_snapshot',
            payload,
            target_tab_id=target_tab_id,
        )

    def handle_client_error(self, monitor_session_id: str, message: str):
        with self._lock:
            item = self._sessions.get(str(monitor_session_id or ''))
            if not item:
                return
            item['status'] = 'error'
            item['error'] = str(message or 'Device monitor failed')
            item['closed_at'] = time.time()
            event_item = self._serialize(item)

        self._publish_status(event_item, 'error')

    def handle_client_closed(self, monitor_session_id: str):
        with self._lock:
            item = self._sessions.get(str(monitor_session_id or ''))
            if not item:
                return
            item['status'] = 'closed'
            item['closed_at'] = time.time()
            event_item = self._serialize(item)
            self._sessions.pop(item['monitor_session_id'], None)

        self._publish_status(event_item, 'closed')

    def handle_client_disconnected(self, client_id: str):
        client_id = str(client_id or '').strip()
        event_items = []
        with self._lock:
            session_ids = [
                session_id
                for session_id, item in self._sessions.items()
                if item.get('client_id') == client_id
            ]
            for session_id in session_ids:
                item = self._sessions.pop(session_id, None)
                if not item:
                    continue
                item['status'] = 'closed'
                item['closed_at'] = time.time()
                item['error'] = 'Client disconnected'
                event_items.append(self._serialize(item))

        for event_item in event_items:
            self._publish_status(event_item, 'closed')

    def _close_existing_tab_sessions(self, tab_id: str):
        with self._lock:
            session_ids = [
                item['monitor_session_id']
                for item in self._sessions.values()
                if item.get('tab_id') == tab_id and item.get('status') not in ('closed', 'error')
            ]
        for monitor_session_id in session_ids:
            try:
                self.close_session(monitor_session_id, tab_id=tab_id)
            except Exception:
                pass

    def _publish_status(self, item: dict, state: str):
        self.event_bus.publish(
            'device_monitor_status',
            {
                **item,
                'state': state,
                'time': datetime.now().isoformat(),
            },
            target_tab_id=item.get('tab_id') or '',
        )

    def _serialize(self, item: dict) -> dict:
        return {
            'monitor_session_id': item.get('monitor_session_id', ''),
            'client_id': item.get('client_id', ''),
            'tab_id': item.get('tab_id', ''),
            'status': item.get('status', ''),
            'channels': list(item.get('channels') or []),
            'intervals': dict(item.get('intervals') or {}),
            'created_at': item.get('created_at') or 0,
            'opened_at': item.get('opened_at') or 0,
            'closed_at': item.get('closed_at') or 0,
            'last_snapshot_at': item.get('last_snapshot_at') or 0,
            'error': item.get('error', ''),
        }

    def _get_required(self, monitor_session_id: str) -> dict:
        with self._lock:
            item = self._sessions.get(str(monitor_session_id or '').strip())
            if item:
                return item
        raise KeyError('Device monitor session not found')

    def _get_required_for_tab(self, monitor_session_id: str, tab_id: str) -> dict:
        item = self._get_required(monitor_session_id)
        normalized_tab_id = str(tab_id or '').strip()
        if normalized_tab_id and item.get('tab_id') != normalized_tab_id:
            raise PermissionError('Device monitor session belongs to another tab')
        return item

    def _normalize_channels(self, channels) -> list[str]:
        raw = channels if isinstance(channels, (list, tuple, set)) else []
        normalized = []
        for channel in raw:
            name = str(channel or '').strip().lower()
            if name in self.SUPPORTED_CHANNELS and name not in normalized:
                normalized.append(name)
        return normalized or ['system', 'storage', 'network', 'battery']

    def _normalize_intervals(self, intervals, channels) -> dict:
        raw = intervals if isinstance(intervals, dict) else {}
        result = {}
        for channel in channels:
            default = self.DEFAULT_INTERVALS[channel]
            try:
                value = float(raw.get(channel, default))
            except Exception:
                value = default
            result[channel] = max(self.MIN_INTERVAL_SECONDS, min(self.MAX_INTERVAL_SECONDS, value))
        return result
