from server.connection.services.heartbeat_service import SessionHeartbeatService
from server.connection.services.message_dispatcher import ServerInboundMessageDispatcher
from server.connection.services.message_router import ServerInboundMessageRouter
from server.connection.services.result_dispatcher import ServerResultDispatcher


class ClientSessionServices:
    """
    客户端会话服务集合。
    旧 socket 文件接收 / artifact ingest 服务已移除。
    """

    def __init__(self, session):
        self.session = session

        self.result_dispatcher = ServerResultDispatcher(session)
        self.message_router = ServerInboundMessageRouter(session)
        self.message_dispatcher = ServerInboundMessageDispatcher(session)
        self.heartbeat_service = SessionHeartbeatService(session)
