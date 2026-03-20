from server.application.artifact.ingest_service import ArtifactIngestService
from server.connection.services.file_receiver import ClientFileReceiver
from server.connection.services.heartbeat_service import SessionHeartbeatService
from server.connection.services.message_dispatcher import ServerInboundMessageDispatcher
from server.connection.services.message_router import ServerInboundMessageRouter
from server.connection.services.result_dispatcher import ServerResultDispatcher


class ClientSessionServices:
    """
    客户端会话服务集合。

    职责：
    - 统一管理围绕 session 工作的 helper / service
    - 将消息分发、结果分发、文件接收、artifact 编排、heartbeat 从 session 本体中剥离
    """

    def __init__(self, session):
        self.session = session

        self.result_dispatcher = ServerResultDispatcher(session)
        self.message_router = ServerInboundMessageRouter(session)
        self.message_dispatcher = ServerInboundMessageDispatcher(session)
        self.file_receiver = ClientFileReceiver(session)
        self.artifact_ingest_service = ArtifactIngestService(session)
        self.heartbeat_service = SessionHeartbeatService(session)