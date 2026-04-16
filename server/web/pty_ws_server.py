import asyncio
import json
import threading
from urllib.parse import parse_qs, urlparse

from websockets.legacy.server import serve

from core.utils.logger import logger
from server.config.config import WEB_HOST, WEB_WS_PORT


class PtyWebSocketServer:
    def __init__(self, server_instance, host=None, port=None):
        self.server = server_instance
        self.host = host or WEB_HOST
        self.port = int(port or WEB_WS_PORT)
        self._thread = None
        self._loop = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def _run_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())
        self._loop.run_forever()

    async def _serve(self):
        async def handler(ws, path):
            await self._handle_client(ws, path)

        server = await serve(
            handler,
            self.host,
            self.port,
            ping_interval=20,
            ping_timeout=20,
            max_size=2**22,
        )
        logger.info('PTY WebSocket listening on %s:%s', self.host, self.port)
        return server

    async def _handle_client(self, ws, path: str):
        parsed = urlparse(path)
        if parsed.path != '/ws/pty':
            await ws.close(code=1008, reason='invalid path')
            return

        query = parse_qs(parsed.query or '')
        pty_session_id = str((query.get('pty_session_id') or [''])[0]).strip()
        token = str((query.get('token') or [''])[0]).strip()
        service = self.server.web_service.terminal_api.pty_session_service
        if not service.authorize_ws(pty_session_id, token):
            await ws.close(code=1008, reason='unauthorized')
            return

        after_seq = 0
        try:
            snapshot = service.get_updates(pty_session_id, after_seq=0)
            after_seq = int(snapshot.get('seq') or 0)
            await ws.send(json.dumps({
                'type': 'snapshot',
                'pty_session_id': pty_session_id,
                'status': snapshot.get('status') or '',
                'seq': after_seq,
                'chunks': snapshot.get('chunks') or [],
                'error': snapshot.get('error') or '',
                'cols': snapshot.get('cols') or 120,
                'rows': snapshot.get('rows') or 32,
            }))
        except Exception as e:
            await ws.send(json.dumps({'type': 'error', 'message': str(e)}))
            await ws.close(code=1011, reason='snapshot failed')
            return

        sender_task = asyncio.create_task(self._sender_loop(ws, service, pty_session_id, after_seq))
        receiver_task = asyncio.create_task(self._receiver_loop(ws, service, pty_session_id))
        done, pending = await asyncio.wait(
            [sender_task, receiver_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        for task in done:
            try:
                await task
            except Exception:
                pass

    async def _sender_loop(self, ws, service, pty_session_id: str, after_seq: int):
        while True:
            updates = service.get_updates(pty_session_id, after_seq=after_seq)
            seq = int(updates.get('seq') or 0)
            chunks = updates.get('chunks') or []
            if chunks or updates.get('status') in ['closed', 'error']:
                await ws.send(json.dumps({
                    'type': 'pty_update',
                    'pty_session_id': pty_session_id,
                    'status': updates.get('status') or '',
                    'seq': seq,
                    'chunks': chunks,
                    'error': updates.get('error') or '',
                    'cols': updates.get('cols') or 120,
                    'rows': updates.get('rows') or 32,
                }))
            after_seq = max(after_seq, seq)
            if updates.get('status') in ['closed', 'error']:
                return
            await asyncio.sleep(0.05)

    async def _receiver_loop(self, ws, service, pty_session_id: str):
        async for raw in ws:
            try:
                payload = json.loads(raw or '{}')
            except Exception:
                continue
            msg_type = str(payload.get('type') or '').strip().lower()
            if msg_type == 'input':
                service.write_input(pty_session_id, str(payload.get('data') or ''))
            elif msg_type == 'resize':
                service.resize_session(
                    pty_session_id,
                    int(payload.get('cols') or 0),
                    int(payload.get('rows') or 0),
                )
            elif msg_type == 'close':
                service.close_session(pty_session_id)
                return
            elif msg_type == 'ping':
                await ws.send(json.dumps({'type': 'pong'}))
