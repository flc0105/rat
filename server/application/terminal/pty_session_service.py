import base64
import secrets
import threading
import time
import uuid

from core.protocol.message_types import (
    MSG_TYPE_PTY_CLOSE,
    MSG_TYPE_PTY_INPUT,
    MSG_TYPE_PTY_OPEN,
    MSG_TYPE_PTY_RESIZE,
)


class PtySessionService:
    def __init__(self, server):
        self.server = server
        self._lock = threading.RLock()
        self._sessions = {}
        self.max_chunks = 500

    def create_session(self, client_id: str, cols: int = 120, rows: int = 32, shell: str = '', cwd: str = '') -> dict:
        session = self.server.get_target_connection_by_client_id(client_id)
        pty_id = str(uuid.uuid4())
        now = time.time()
        item = {
            'pty_session_id': pty_id,
            'client_id': client_id,
            'status': 'opening',
            'created_at': now,
            'opened_at': 0,
            'closed_at': 0,
            'shell': shell or '',
            'cwd': cwd or '',
            'cols': max(20, int(cols or 120)),
            'rows': max(5, int(rows or 32)),
            'seq': 0,
            'chunks': [],
            'error': '',
            'ws_token': secrets.token_urlsafe(24),
        }
        with self._lock:
            self._sessions[pty_id] = item

        session.send({
            'type': MSG_TYPE_PTY_OPEN,
            'pty_session_id': pty_id,
            'shell': item['shell'],
            'cwd': item['cwd'],
            'cols': item['cols'],
            'rows': item['rows'],
        })
        return {
            'pty_session_id': pty_id,
            'status': item['status'],
            'cols': item['cols'],
            'rows': item['rows'],
            'ws_token': item['ws_token'],
        }


    def authorize_ws(self, pty_session_id: str, token: str) -> bool:
        with self._lock:
            item = self._sessions.get(str(pty_session_id))
            if not item:
                return False
            return str(item.get('ws_token') or '') == str(token or '')

    def write_input(self, pty_session_id: str, data: str):
        item = self._get_required(pty_session_id)
        session = self.server.get_target_connection_by_client_id(item['client_id'])
        session.send({
            'type': MSG_TYPE_PTY_INPUT,
            'pty_session_id': pty_session_id,
            'data': data or '',
        })
        return {'ok': True}

    def resize_session(self, pty_session_id: str, cols: int, rows: int):
        item = self._get_required(pty_session_id)
        cols = max(20, int(cols or item['cols'] or 120))
        rows = max(5, int(rows or item['rows'] or 32))
        with self._lock:
            item['cols'] = cols
            item['rows'] = rows
        session = self.server.get_target_connection_by_client_id(item['client_id'])
        session.send({
            'type': MSG_TYPE_PTY_RESIZE,
            'pty_session_id': pty_session_id,
            'cols': cols,
            'rows': rows,
        })
        return {'ok': True}

    def close_session(self, pty_session_id: str):
        item = self._get_required(pty_session_id)
        session = self.server.get_target_connection_by_client_id(item['client_id'])
        try:
            session.send({
                'type': MSG_TYPE_PTY_CLOSE,
                'pty_session_id': pty_session_id,
            })
        except Exception:
            pass
        with self._lock:
            item['status'] = 'closed'
            item['closed_at'] = time.time()
        return {'ok': True}

    def get_updates(self, pty_session_id: str, after_seq: int = 0) -> dict:
        item = self._get_required(pty_session_id)
        with self._lock:
            chunks = [chunk for chunk in item['chunks'] if int(chunk.get('seq') or 0) > int(after_seq or 0)]
            return {
                'pty_session_id': pty_session_id,
                'status': item['status'],
                'seq': item['seq'],
                'chunks': chunks,
                'error': item.get('error') or '',
                'cols': item.get('cols') or 120,
                'rows': item.get('rows') or 32,
            }

    def handle_client_opened(self, pty_session_id: str):
        with self._lock:
            item = self._sessions.get(pty_session_id)
            if not item:
                return
            item['status'] = 'open'
            item['opened_at'] = time.time()

    def handle_client_output(self, pty_session_id: str, data: str):
        text = ''
        try:
            raw = base64.b64decode(str(data or '').encode(), validate=False)
            text = raw.decode('utf-8', errors='replace')
        except Exception:
            text = str(data or '')
        with self._lock:
            item = self._sessions.get(pty_session_id)
            if not item:
                return
            item['seq'] += 1
            item['chunks'].append({'seq': item['seq'], 'text': text})
            if len(item['chunks']) > self.max_chunks:
                item['chunks'] = item['chunks'][-self.max_chunks:]

    def handle_client_closed(self, pty_session_id: str, exit_code=0):
        with self._lock:
            item = self._sessions.get(pty_session_id)
            if not item:
                return
            item['status'] = 'closed'
            item['closed_at'] = time.time()
            item['exit_code'] = exit_code

    def handle_client_error(self, pty_session_id: str, message: str):
        with self._lock:
            item = self._sessions.get(pty_session_id)
            if not item:
                return
            item['status'] = 'error'
            item['error'] = str(message or 'PTY error')
            item['closed_at'] = time.time()
            item['seq'] += 1
            item['chunks'].append({'seq': item['seq'], 'text': f"\n[PTY error] {item['error']}\n"})
            if len(item['chunks']) > self.max_chunks:
                item['chunks'] = item['chunks'][-self.max_chunks:]

    def _get_required(self, pty_session_id: str) -> dict:
        with self._lock:
            item = self._sessions.get(str(pty_session_id))
            if item is not None:
                return item
        raise KeyError('PTY session not found')
