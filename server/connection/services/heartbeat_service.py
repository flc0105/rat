from datetime import datetime

from core.protocol.message_types import MSG_TYPE_HEARTBEAT


class SessionHeartbeatService:
    def __init__(self, session):
        self.session = session

    def _now_iso(self) -> str:
        return datetime.now().isoformat()

    def mark_connected(self):
        now = self._now_iso()
        self.session.context.connected_at = now
        self.session.context.disconnected_at = ''
        self.session.context.last_seen_at = now

    def mark_disconnected(self):
        self.session.context.disconnected_at = self._now_iso()

    def send_heartbeat(self):
        heartbeat_id = self.session.command_channel.generate_message_id()
        now_iso = self._now_iso()

        self.session.context.last_heartbeat_id = heartbeat_id
        self.session.context.last_heartbeat_sent_at = now_iso

        self.session.send({
            'type': MSG_TYPE_HEARTBEAT,
            'id': heartbeat_id,
            'ts': now_iso,
        })

    def handle_heartbeat_ack(self, data: dict):
        now_iso = self._now_iso()
        self.session.context.last_seen_at = now_iso
        self.session.context.last_heartbeat_ack_at = now_iso

        ack_id = data.get('id')
        if ack_id is not None:
            self.session.context.last_heartbeat_id = ack_id

        server_ts = str(data.get('server_ts') or '').strip()
        if server_ts:
            try:
                sent_dt = datetime.fromisoformat(server_ts)
                rtt_ms = max(int((datetime.now() - sent_dt).total_seconds() * 1000), 0)
                self.session.context.last_rtt_ms = rtt_ms
            except Exception:
                pass

        callback = self.session.context.on_heartbeat_updated
        if callable(callback):
            try:
                callback(self.session)
            except Exception:
                pass









