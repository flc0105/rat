from server.application.artifact.ingest_service import ArtifactIngestService
from server.connection.file_receiver import ClientFileReceiver
from server.connection.message_dispatcher import ServerInboundMessageDispatcher
from server.connection.message_router import ServerInboundMessageRouter
from server.connection.result_dispatcher import ServerResultDispatcher


class ClientSessionServices:
    """
    客户端会话服务集合。

    职责：
    - 统一管理围绕连接会话工作的 helper / service
    - 将消息分发、结果分发、文件接收、artifact 编排从 ClientConnection 本体中剥离
    """

    def __init__(self, connection):
        self.connection = connection

        self.result_dispatcher = ServerResultDispatcher(connection)
        self.message_router = ServerInboundMessageRouter(connection)
        self.message_dispatcher = ServerInboundMessageDispatcher(connection)
        self.file_receiver = ClientFileReceiver(connection)
        self.artifact_ingest_service = ArtifactIngestService(connection)