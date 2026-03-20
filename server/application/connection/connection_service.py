from datetime import datetime

from server.connection.client_session import ClientSession
from server.connection.transport.client_transport import ClientTransport


class WebConnectionService:
    """
    Web 连接服务。

    职责：
    - 序列化连接信息
    - 创建带 Web 能力的客户端会话对象
    - 处理连接上线/下线/背景消息事件
    """

    def __init__(self, server, event_bus, artifact_service):
        self.server = server
        self.event_bus = event_bus
        self.artifact_service = artifact_service

    # ------------------ payload ------------------ #
    def serialize_connection(self, session: ClientSession) -> dict:
        info = session.info or {}
        return {
            'client_id': info.get('id'),
            'addr': info.get('addr', ''),
            'os_type': info.get('os_type', 'Unknown'),
            'os_ver': info.get('os_ver', 'Unknown'),
            'hostname': info.get('hostname', 'Unknown'),
            'integrity': info.get('integrity', '?'),
            'cwd': info.get('cwd', ''),
        }

    def get_connections_payload(self):
        return [self.serialize_connection(session) for session in self.server.connections.all()]

    # ------------------ connection lifecycle ------------------ #
    def create_web_connection(self, transport: ClientTransport, addr, info: dict) -> ClientSession:
        """
        创建并配置带 Web 能力的客户端会话对象
        """
        session = ClientSession(transport, info)
        session.context.command_history = self.server.command_history
        session.context.artifact_service = self.artifact_service

        session.context.on_file_saved = (
            lambda artifact_info: self.publish_file_received(info.get('id'), artifact_info)
        )
        session.context.on_unexpected_message = (
            lambda status, text, end: self.publish_background_message(session, status, text, end)
        )
        return session

    def handle_connection_registered(self, session: ClientSession):
        """
        连接注册成功后的 Web 通知
        """
        self.publish_connection_online(session)

    def handle_connection_closed(self, session: ClientSession):
        """
        连接关闭后的 Web 通知
        """
        self.publish_connection_offline(session)

    # ------------------ event publish ------------------ #
    def publish_connection_online(self, session: ClientSession):
        self.event_bus.publish('connection_online', {
            'connection': self.serialize_connection(session),
            'time': datetime.now().isoformat()
        })

    def publish_connection_offline(self, session: ClientSession):
        self.event_bus.publish('connection_offline', {
            'client_id': session.info.get('id'),
            'time': datetime.now().isoformat()
        })

    def publish_background_message(self, session: ClientSession, status, text, end):
        self.event_bus.publish('background_message', {
            'client_id': session.info.get('id'),
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
            'original_name': artifact_info.get('original_name', ''),
            'stored_name': artifact_info.get('stored_name', ''),
            'size': artifact_info.get('size', 0),
            'created_at': artifact_info.get('created_at', ''),
            'download_url': artifact_info.get('download_url', ''),
            'preview_url': artifact_info.get('preview_url', ''),
        })