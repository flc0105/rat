from server.web.connection_service import WebConnectionService
from server.web.event_bus import WebEventBus
from server.web.file_service import WebFileService
from server.web.task_service import WebTaskService
from server.web.task_store import WebTaskStore


class ServerWebService:
    """
    Server 的 Web 门面服务。

    职责：
    - 聚合 Web 侧各个子服务
    - 对外暴露稳定接口，避免 app.py / server.py 直接依赖过多内部实现
    """

    def __init__(self, server):
        self.server = server
        self.event_bus = WebEventBus()
        self.task_store = WebTaskStore()
        self.file_service = WebFileService()

        self.connection_service = WebConnectionService(
            server=self.server,
            event_bus=self.event_bus,
            file_service=self.file_service,
        )

        self.task_service = WebTaskService(
            server=self.server,
            event_bus=self.event_bus,
            task_store=self.task_store,
            file_service=self.file_service,
        )

    # ------------------ connection facade ------------------ #
    def get_connections_payload(self):
        return self.connection_service.get_connections_payload()

    def create_web_connection(self, conn, addr, info: dict):
        return self.connection_service.create_web_connection(conn, addr, info)

    def handle_connection_registered(self, connection):
        self.connection_service.handle_connection_registered(connection)

    def handle_connection_closed(self, conn):
        self.connection_service.handle_connection_closed(conn)

    # ------------------ task facade ------------------ #
    def submit_web_command(self, client_id: str, command: str):
        return self.task_service.submit_web_command(client_id, command)

    def submit_web_upload(self, client_id: str, local_path: str, display_name: str):
        return self.task_service.submit_web_upload(client_id, local_path, display_name)

    # ------------------ compatibility facade ------------------ #
    def build_connection(self, conn, addr, info: dict):
        return self.create_web_connection(conn, addr, info)

    def on_connection_registered(self, connection):
        self.handle_connection_registered(connection)

    def on_connection_closed(self, conn):
        self.handle_connection_closed(conn)

    def submit_command(self, client_id: str, command: str):
        return self.submit_web_command(client_id, command)

    def submit_upload(self, client_id: str, local_path: str, display_name: str):
        return self.submit_web_upload(client_id, local_path, display_name)