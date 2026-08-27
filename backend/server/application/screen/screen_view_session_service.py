import secrets
import threading
import time
import uuid

from core.protocol.message_types import (
    MSG_TYPE_SCREEN_CLOSE,
    MSG_TYPE_SCREEN_CONFIG,
    MSG_TYPE_SCREEN_INPUT,
    MSG_TYPE_SCREEN_OPEN,
)


class ScreenViewSessionService:
    """
    Server 端只读屏幕预览会话。

    只保留每个会话的最新一帧，避免实时预览产生无意义的帧积压。
    """

    MIN_FPS = 1
    MAX_FPS = 10
    MIN_QUALITY = 20
    MAX_QUALITY = 95

    def __init__(self, server):
        self.server = server
        self._lock = threading.RLock()
        self._sessions = {}

    def create_session(self, client_id: str, fps: int = 4, quality: int = 60) -> dict:
        client_id = str(client_id or '').strip()
        session = self.server.get_target_connection_by_client_id(client_id)
        self._cleanup_expired_sessions()
        self._close_existing_client_sessions(client_id)

        screen_session_id = str(uuid.uuid4())
        item = {
            'screen_session_id': screen_session_id,
            'client_id': client_id,
            'status': 'opening',
            'created_at': time.time(),
            'opened_at': 0,
            'closed_at': 0,
            'fps': self._normalize_fps(fps),
            'quality': self._normalize_quality(quality),
            'seq': 0,
            'frame': '',
            'width': 0,
            'height': 0,
            'frame_bytes': 0,
            'captured_at': 0,
            'error': '',
            'control_enabled': False,
            'control_error': '',
            'ws_token': secrets.token_urlsafe(24),
        }
        with self._lock:
            self._sessions[screen_session_id] = item

        session.send({
            'type': MSG_TYPE_SCREEN_OPEN,
            'screen_session_id': screen_session_id,
            'fps': item['fps'],
            'quality': item['quality'],
        })

        return {
            'screen_session_id': screen_session_id,
            'status': item['status'],
            'fps': item['fps'],
            'quality': item['quality'],
            'ws_token': item['ws_token'],
        }

    def update_settings(self, screen_session_id: str, fps=None, quality=None) -> dict:
        item = self._get_required(screen_session_id)
        next_fps = self._normalize_fps(item['fps'] if fps is None else fps)
        next_quality = self._normalize_quality(item['quality'] if quality is None else quality)

        with self._lock:
            item['fps'] = next_fps
            item['quality'] = next_quality

        session = self.server.get_target_connection_by_client_id(item['client_id'])
        session.send({
            'type': MSG_TYPE_SCREEN_CONFIG,
            'screen_session_id': item['screen_session_id'],
            'fps': next_fps,
            'quality': next_quality,
        })
        return {'ok': True, 'fps': next_fps, 'quality': next_quality}

    def set_control_enabled(self, screen_session_id: str, enabled: bool) -> dict:
        item = self._get_required(screen_session_id)
        next_enabled = bool(enabled)
        with self._lock:
            item['control_enabled'] = next_enabled
            item['control_error'] = ''

        event = {'action': 'prepare' if next_enabled else 'control_off'}
        self._send_input_event(item, event)
        return {'ok': True, 'control_enabled': next_enabled}

    def send_input(self, screen_session_id: str, event: dict) -> dict:
        item = self._get_required(screen_session_id)
        with self._lock:
            if not item.get('control_enabled'):
                return {'ok': False, 'control_enabled': False}

        normalized = self._normalize_input_event(event)
        self._send_input_event(item, normalized)
        return {'ok': True, 'control_enabled': True}

    def close_session(self, screen_session_id: str) -> dict:
        item = self._get_required(screen_session_id)
        try:
            session = self.server.get_target_connection_by_client_id(item['client_id'])
            session.send({
                'type': MSG_TYPE_SCREEN_CLOSE,
                'screen_session_id': item['screen_session_id'],
            })
        except Exception:
            pass

        with self._lock:
            item['control_enabled'] = False
            if item['status'] not in ('closed', 'error'):
                item['status'] = 'closing'
        return {'ok': True}

    def get_updates(self, screen_session_id: str, after_seq: int = 0) -> dict:
        item = self._get_required(screen_session_id)
        with self._lock:
            seq = int(item.get('seq') or 0)
            frame = item.get('frame') or '' if seq > int(after_seq or 0) else ''
            return {
                'screen_session_id': item['screen_session_id'],
                'status': item.get('status') or '',
                'seq': seq,
                'frame': frame,
                'width': int(item.get('width') or 0),
                'height': int(item.get('height') or 0),
                'frame_bytes': int(item.get('frame_bytes') or 0),
                'captured_at': item.get('captured_at') or 0,
                'fps': int(item.get('fps') or 4),
                'quality': int(item.get('quality') or 60),
                'error': item.get('error') or '',
                'control_enabled': bool(item.get('control_enabled')),
                'control_error': item.get('control_error') or '',
            }

    def handle_client_opened(self, screen_session_id: str, fps=None, quality=None):
        with self._lock:
            item = self._sessions.get(str(screen_session_id or ''))
            if not item:
                return
            item['status'] = 'open'
            item['opened_at'] = time.time()
            if fps is not None:
                item['fps'] = self._normalize_fps(fps)
            if quality is not None:
                item['quality'] = self._normalize_quality(quality)

    def handle_client_frame(self, screen_session_id: str, data: str, width=0, height=0, frame_bytes=0, captured_at=0):
        if not data:
            return
        with self._lock:
            item = self._sessions.get(str(screen_session_id or ''))
            if not item:
                return
            item['status'] = 'open'
            item['seq'] += 1
            item['frame'] = str(data)
            item['width'] = int(width or 0)
            item['height'] = int(height or 0)
            item['frame_bytes'] = int(frame_bytes or 0)
            item['captured_at'] = captured_at or time.time()

    def handle_client_closed(self, screen_session_id: str):
        with self._lock:
            item = self._sessions.get(str(screen_session_id or ''))
            if not item:
                return
            item['status'] = 'closed'
            item['closed_at'] = time.time()
            item['control_enabled'] = False

    def handle_client_error(self, screen_session_id: str, message: str):
        with self._lock:
            item = self._sessions.get(str(screen_session_id or ''))
            if not item:
                return
            item['status'] = 'error'
            item['error'] = str(message or 'Screen capture failed')
            item['closed_at'] = time.time()
            item['control_enabled'] = False

    def handle_client_input_error(self, screen_session_id: str, message: str):
        with self._lock:
            item = self._sessions.get(str(screen_session_id or ''))
            if not item:
                return
            item['control_enabled'] = False
            item['control_error'] = str(message or 'Screen control input failed')

    def handle_client_disconnected(self, client_id: str):
        client_id = str(client_id or '').strip()
        now = time.time()
        with self._lock:
            for item in self._sessions.values():
                if item.get('client_id') != client_id:
                    continue
                if item.get('status') in ('closed', 'error'):
                    continue
                item['status'] = 'closed'
                item['closed_at'] = now
                item['error'] = 'Client disconnected'
                item['control_enabled'] = False

    def authorize_ws(self, screen_session_id: str, token: str) -> bool:
        with self._lock:
            item = self._sessions.get(str(screen_session_id or ''))
            if not item:
                return False
            expected = str(item.get('ws_token') or '')
        return bool(expected) and bool(token) and secrets.compare_digest(expected, str(token))

    def _close_existing_client_sessions(self, client_id: str):
        with self._lock:
            session_ids = [
                item['screen_session_id']
                for item in self._sessions.values()
                if item.get('client_id') == client_id and item.get('status') not in ('closed', 'error')
            ]
        for screen_session_id in session_ids:
            try:
                self.close_session(screen_session_id)
            except Exception:
                pass

    def _send_input_event(self, item: dict, event: dict):
        session = self.server.get_target_connection_by_client_id(item['client_id'])
        session.send({
            'type': MSG_TYPE_SCREEN_INPUT,
            'screen_session_id': item['screen_session_id'],
            'event': event,
        })

    def _normalize_input_event(self, event: dict) -> dict:
        payload = event if isinstance(event, dict) else {}
        action = str(payload.get('action') or '').strip().lower()
        allowed = {
            'mouse_move',
            'mouse_down',
            'mouse_up',
            'mouse_wheel',
            'key_down',
            'key_up',
            'release_all',
        }
        if action not in allowed:
            raise ValueError(f'Unsupported screen input action: {action or "missing"}')

        result = {'action': action}
        if action.startswith('mouse_') and action != 'mouse_wheel':
            result['x'] = self._normalize_pointer(payload.get('x'))
            result['y'] = self._normalize_pointer(payload.get('y'))
        elif action == 'mouse_wheel':
            result['x'] = self._normalize_pointer(payload.get('x'))
            result['y'] = self._normalize_pointer(payload.get('y'))
            try:
                delta = int(payload.get('delta') or 0)
            except Exception:
                delta = 0
            result['delta'] = max(-10, min(10, delta))

        if action in ('mouse_down', 'mouse_up'):
            button = str(payload.get('button') or '').strip().lower()
            if button not in ('left', 'middle', 'right'):
                raise ValueError('Unsupported screen mouse button')
            result['button'] = button

        # if action in ('key_down', 'key_up'):
        #     key = str(payload.get('key') or '').strip()
        #     if not key or len(key) > 32:
        #         raise ValueError('Invalid screen keyboard key')
        #     result['key'] = key

        if action in ('key_down', 'key_up'):
            key = str(payload.get('key') or '').strip()
            if not key or len(key) > 32:
                raise ValueError('Invalid screen keyboard key')
            result['key'] = key

            if action == 'key_down':
                result['repeat'] = bool(payload.get('repeat'))

        return result

    def _normalize_pointer(self, value) -> float:
        try:
            normalized = float(value)
        except Exception as e:
            raise ValueError('Invalid screen pointer coordinate') from e
        return max(0.0, min(1.0, normalized))

    def _cleanup_expired_sessions(self):
        cutoff = time.time() - 300
        with self._lock:
            expired = [
                screen_session_id
                for screen_session_id, item in self._sessions.items()
                if item.get('status') in ('closed', 'error') and float(item.get('closed_at') or 0) < cutoff
            ]
            for screen_session_id in expired:
                self._sessions.pop(screen_session_id, None)

    def _get_required(self, screen_session_id: str) -> dict:
        with self._lock:
            item = self._sessions.get(str(screen_session_id or ''))
            if item is not None:
                return item
        raise KeyError('Screen view session not found')

    def _normalize_fps(self, value) -> int:
        try:
            normalized = int(value)
        except Exception:
            normalized = 4
        return max(self.MIN_FPS, min(self.MAX_FPS, normalized))

    def _normalize_quality(self, value) -> int:
        try:
            normalized = int(value)
        except Exception:
            normalized = 60
        return max(self.MIN_QUALITY, min(self.MAX_QUALITY, normalized))
