from server.application.agent.agent_builder import AgentBuilder
from server.application.artifact.artifact_service import WebArtifactService
from server.application.artifact.remote_file_service import WebRemoteFileService
from server.application.connection.connection_service import WebConnectionService
from server.application.execution.remote_execution_service import RemoteExecutionService
from server.application.jobs.background_job_service import BackgroundJobService
from server.application.jobs.background_job_store import BackgroundJobStore
from server.application.script.script_service import ServerJobService
from server.application.tasks.task_runner import WebTaskRunner
from server.application.tasks.task_service import WebTaskService
from server.application.tasks.task_store import WebTaskStore
from server.config.config import SCRIPT_JOBS_PATH
from server.web.event_bus import WebEventBus


class ServerApplicationAssembly:
    """
    Server 应用装配层。

    职责：
    - 统一实例化应用层依赖
    - 统一处理跨 service/store 的依赖绑定
    - 为 Application Facade 提供已经组装完成的依赖对象

    说明：
    - 这里不承载具体业务逻辑
    - 这里只负责“怎么创建”和“怎么接线”
    """

    def __init__(self, server):
        self.server = server

        # ------------------ shared infrastructure ------------------ #
        self.event_bus = WebEventBus()
        self.task_store = WebTaskStore()

        # ------------------ domain/application services ------------------ #
        self.artifact_service = WebArtifactService()
        self.file_service = self.artifact_service

        self.remote_execution_service = RemoteExecutionService(self.server)

        self.remote_file_service = WebRemoteFileService(
            remote_execution_service=self.remote_execution_service,
            artifact_service=self.artifact_service,
        )

        self.connection_service = WebConnectionService(
            server=self.server,
            event_bus=self.event_bus,
            artifact_service=self.artifact_service,
        )

        self.task_runner = WebTaskRunner(
            server=self.server,
            event_bus=self.event_bus,
            task_store=self.task_store,
        )

        self.task_service = WebTaskService(
            server=self.server,
            task_store=self.task_store,
            file_service=self.file_service,
            task_runner=self.task_runner,
        )

        self.background_job_store = BackgroundJobStore()

        self.background_job_service = BackgroundJobService(
            event_bus=self.event_bus,
            job_store=self.background_job_store,
            remote_execution_service=self.remote_execution_service,
        )

        self.script_service = ServerJobService(SCRIPT_JOBS_PATH)
        self.agent_builder = AgentBuilder()

        self._wire_cross_dependencies()

    def _wire_cross_dependencies(self):
        """
        统一处理跨对象依赖绑定。

        这类 wiring 原本散落在 Facade 中，
        现在收口到 assembly，避免 Facade 同时承担装配职责。
        """
        self.background_job_store.artifact_service = self.artifact_service
        self.server.command_history.artifact_service = self.artifact_service








