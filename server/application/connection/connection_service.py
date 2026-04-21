from datetime import datetime

from server.connection.client_session import ClientSession
from server.connection.transport.client_transport import ClientTransport


class WebConnectionService:
    """
    Web 连接服务。

    职责：
    - 序列化连接信息
    - 创建带 Web 能力的客户端会话对象
    - 处理连接上线/下线/心跳状态事件
    - 维护最近见过的设备缓存
    """

    STALE_AFTER_SECONDS = 45

    def __init__(self, server, event_bus, artifact_service, recent_device_store=None):
        self.server = server
        self.event_bus = event_bus
        self.artifact_service = artifact_service
        self.recent_device_store = recent_device_store

    def _now(self):
        return datetime.now()

    def _safe_parse_iso(self, value: str):
        text = str(value or '').strip()
        if not text:
            return None
        try:
            return datetime.fromisoformat(text)
        except Exception:
            return None

    def _build_connection_state(self, session: ClientSession) -> str:
        disconnected_at = self._safe_parse_iso(session.context.disconnected_at)
        if disconnected_at is not None:
            return 'offline'

        last_seen_at = self._safe_parse_iso(session.context.last_seen_at)
        if last_seen_at is None:
            return 'online'

        age_seconds = max((self._now() - last_seen_at).total_seconds(), 0)
        if age_seconds > self.STALE_AFTER_SECONDS:
            return 'stale'

        return 'online'

    def _machine_key(self, machine_id: str) -> str:
        return str(machine_id or '').strip().lower()

    # ------------------ payload ------------------ #
    def serialize_connection(self, session: ClientSession) -> dict:
        info = session.session_info
        return {
            'client_id': info.client_id,
            'addr': info.addr,
            'hostname': info.hostname,
            'machine_id': info.machine_id,
            'machine_id_version': info.machine_id_version,
            'machine_fingerprint_basis': info.machine_fingerprint_basis,
            'os_type': info.os_type,
            'os_alias': info.os_alias,
            'os_ver': info.os_ver,
            'integrity': info.integrity,
            'cwd': info.cwd,
            'connected_at': session.context.connected_at,
            'disconnected_at': session.context.disconnected_at,
            'last_seen_at': session.context.last_seen_at,
            'last_heartbeat_sent_at': session.context.last_heartbeat_sent_at,
            'last_heartbeat_ack_at': session.context.last_heartbeat_ack_at,
            'last_rtt_ms': session.context.last_rtt_ms,
            'stale_after_seconds': self.STALE_AFTER_SECONDS,
            'connection_state': self._build_connection_state(session),
            'build_version': info.build_version,
            'python_ver': info.get_extra('python_ver'),
            'process_id': info.get_extra('process_id'),
            'launch_command': info.get_extra('launch_command'),
            'username': info.get_extra('username'),
            'process_name': info.get_extra('process_name'),
            'http_transfer_mode': info.get_extra('http_transfer_mode'),
            'python_execution_mode': info.get_extra('python_execution_mode'),
            'remote_watchdog_enabled': info.get_extra('remote_watchdog_enabled'),
            'local_watchdog_enabled': info.get_extra('local_watchdog_enabled'),
        }

    def _sync_recent_online_connections(self, active_connections: list[dict]):
        if not self.recent_device_store:
            return

        for item in active_connections:
            machine_id = str(item.get('machine_id') or '').strip()
            if not machine_id:
                continue
            self.recent_device_store.upsert_from_connection(item)

    def _build_recent_offline_entries(self, active_connections: list[dict]) -> list[dict]:
        if not self.recent_device_store:
            return []

        active_machine_ids = {
            self._machine_key(item.get('machine_id'))
            for item in active_connections
            if str(item.get('machine_id') or '').strip()
        }

        results = []
        for item in self.recent_device_store.list_recent_devices():
            machine_key = self._machine_key(item.get('machine_id'))
            if not machine_key:
                continue
            if machine_key in active_machine_ids:
                continue

            offline_item = {
                'client_id': item.get('client_id') or '',
                'addr': item.get('addr') or '',
                'hostname': item.get('hostname') or 'Unknown',
                'machine_id': item.get('machine_id') or '',
                'machine_id_version': item.get('machine_id_version') or '',
                'machine_fingerprint_basis': item.get('machine_fingerprint_basis') or '',
                'os_type': item.get('os_type') or 'Unknown',
                'os_alias': item.get('os_alias') or 'unknown',
                'os_ver': item.get('os_ver') or 'Unknown',
                'integrity': item.get('integrity') or '?',
                'cwd': item.get('cwd') or '',
                'connected_at': item.get('connected_at') or '',
                'disconnected_at': item.get('disconnected_at') or '',
                'last_seen_at': item.get('last_seen_at') or '',
                'last_heartbeat_sent_at': item.get('last_heartbeat_sent_at') or '',
                'last_heartbeat_ack_at': item.get('last_heartbeat_ack_at') or '',
                'last_rtt_ms': item.get('last_rtt_ms'),
                'stale_after_seconds': item.get('stale_after_seconds') or self.STALE_AFTER_SECONDS,
                'connection_state': 'offline',
                'build_version': item.get('build_version') or '',
                'python_ver': item.get('python_ver') or '',
                'process_id': item.get('process_id') or '',
                'launch_command': item.get('launch_command') or '',
                'username': item.get('username') or '',
                'process_name': item.get('process_name') or '',
                'http_transfer_mode': item.get('http_transfer_mode') or '',
                'python_execution_mode': item.get('python_execution_mode') or '',
                'remote_watchdog_enabled': item.get('remote_watchdog_enabled'),
                'local_watchdog_enabled': item.get('local_watchdog_enabled'),
                'recent_cached': True,
            }
            results.append(offline_item)

        return results

    def get_connections_payload(self):
        active_connections = [self.serialize_connection(session) for session in self.server.connections.all()]
        self._sync_recent_online_connections(active_connections)
        recent_offline = self._build_recent_offline_entries(active_connections)
        return active_connections + recent_offline

    # ------------------ connection lifecycle ------------------ #
    def create_web_connection(self, transport: ClientTransport, addr, info: dict) -> ClientSession:
        session = ClientSession(transport, info)
        session.context.command_history = self.server.command_history
        session.context.command_history_orchestrator = self.server.command_history_orchestrator
        session.context.artifact_service = self.artifact_service

        session.context.on_unexpected_message = (
            lambda status, text, end: self.publish_background_message(session, status, text, end)
        )
        session.context.on_heartbeat_updated = (
            lambda current_session: self.publish_connection_heartbeat(current_session)
        )
        terminal_service = self.server.web_service.terminal_api.pty_session_service
        session.context.on_pty_opened = terminal_service.handle_client_opened
        session.context.on_pty_output = terminal_service.handle_client_output
        session.context.on_pty_closed = terminal_service.handle_client_closed
        session.context.on_pty_error = terminal_service.handle_client_error
        return session

    def handle_connection_registered(self, session: ClientSession):
        session.services.heartbeat_service.mark_connected()
        payload = self.serialize_connection(session)
        if self.recent_device_store:
            self.recent_device_store.upsert_from_connection(payload)
        self.publish_connection_online(session)

    def handle_connection_closed(self, session: ClientSession):
        session.services.heartbeat_service.mark_disconnected()
        payload = self.serialize_connection(session)
        if self.recent_device_store:
            self.recent_device_store.upsert_from_connection(payload)
            self.recent_device_store.mark_offline(
                machine_id=payload.get('machine_id') or '',
                disconnected_at=payload.get('disconnected_at') or '',
            )
        self.publish_connection_offline(session)

    # ------------------ event publish ------------------ #
    def publish_connection_online(self, session: ClientSession):
        self.event_bus.publish('connection_online', {
            'connection': self.serialize_connection(session),
            'time': datetime.now().isoformat()
        })

    def publish_connection_offline(self, session: ClientSession):
        self.event_bus.publish('connection_offline', {
            'client_id': session.session_info.client_id,
            'connection': self.serialize_connection(session),
            'time': datetime.now().isoformat()
        })

    def publish_connection_heartbeat(self, session: ClientSession):
        payload = self.serialize_connection(session)
        if self.recent_device_store:
            self.recent_device_store.upsert_from_connection(payload)

        self.event_bus.publish('connection_heartbeat', {
            'connection': payload,
            'time': datetime.now().isoformat()
        })

    def publish_background_message(self, session: ClientSession, status, text, end):
        self.event_bus.publish('background_message', {
            'client_id': session.session_info.client_id,
            'status': status,
            'text': text,
            'eof': end,
            'time': datetime.now().isoformat()
        })

    def publish_file_received(self, client_id: str, artifact_info: dict):
        if not isinstance(artifact_info, dict):
            return

        self.event_bus.publish('file_received', {
            'client_id': client_id,
            'artifact_id': artifact_info.get('artifact_id', ''),
            'artifact_type': artifact_info.get('artifact_type', ''),
            'category': artifact_info.get('category', ''),
            'hostname': artifact_info.get('hostname', ''),
            'machine_id': artifact_info.get('machine_id', ''),
            'original_name': artifact_info.get('original_name', ''),
            'stored_name': artifact_info.get('stored_name', ''),
            'size': artifact_info.get('size', 0),
            'created_at': artifact_info.get('created_at', ''),
            'download_url': artifact_info.get('download_url', ''),
            'preview_url': artifact_info.get('preview_url', ''),
        })
