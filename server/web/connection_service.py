from datetime import datetime
import os

from server.connection.client_connection import ClientConnection


class WebConnectionService:
    """
    Web 连接服务。

    职责：
    - 序列化连接信息
    - 创建带 Web 能力的连接对象
    - 处理连接上线/下线/背景消息事件
    """

    def __init__(self, server, event_bus, file_service):
        self.server = server
        self.event_bus = event_bus
        self.file_service = file_service

    # ------------------ payload ------------------ #
    def serialize_connection(self, conn: ClientConnection) -> dict:
        info = conn.info or {}
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
        return [self.serialize_connection(conn) for conn in self.server.connections.all()]

    # ------------------ connection lifecycle ------------------ #
    def create_web_connection(self, conn, addr, info: dict) -> ClientConnection:
        """
        创建并配置带 Web 能力的客户端连接对象
        """
        connection = ClientConnection(
            conn,
            addr,
            info,
            file_save_dir=self.file_service.received_files_dir,
            on_file_saved=lambda original_name, saved_path, size: self.publish_file_received(
                info.get('id'),
                original_name,
                saved_path,
                size
            )
        )
        connection.command_history = self.server.command_history

        connection.on_unexpected_message = (
            lambda status, text, end: self.publish_background_message(connection, status, text, end)
        )
        return connection

    def handle_connection_registered(self, connection: ClientConnection):
        """
        连接注册成功后的 Web 通知
        """
        self.publish_connection_online(connection)

    def handle_connection_closed(self, conn: ClientConnection):
        """
        连接关闭后的 Web 通知
        """
        self.publish_connection_offline(conn)

    # ------------------ event publish ------------------ #
    def publish_connection_online(self, connection: ClientConnection):
        self.event_bus.publish('connection_online', {
            'connection': self.serialize_connection(connection),
            'time': datetime.now().isoformat()
        })

    def publish_connection_offline(self, conn: ClientConnection):
        self.event_bus.publish('connection_offline', {
            'client_id': conn.info.get('id'),
            'time': datetime.now().isoformat()
        })

    def publish_background_message(self, connection: ClientConnection, status, text, end):
        self.event_bus.publish('background_message', {
            'client_id': connection.info.get('id'),
            'status': status,
            'text': text,
            'eof': end,
            'time': datetime.now().isoformat()
        })

    def publish_file_received(self, client_id: str, original_name: str, saved_path: str, size: int):
        self.event_bus.publish('file_received', {
            'client_id': client_id,
            'original_name': original_name,
            'saved_name': os.path.basename(saved_path),
            'saved_path': saved_path,
            'size': size,
            'created_at': datetime.now().isoformat(),
        })