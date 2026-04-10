from server.application.agent.agent_builder import AgentBuilder
from server.application.artifact.artifact_service import WebArtifactService
from server.application.artifact.remote_file_service import WebRemoteFileService
from server.application.command.command_executor_factory import CommandExecutorFactory
from server.application.connection.connection_service import WebConnectionService
from server.application.execution.remote_execution_service import RemoteExecutionService
from server.application.jobs.background_job_service import BackgroundJobService
from server.application.jobs.background_job_store import BackgroundJobStore
from server.application.jobs.job_catalog_service import JobCatalogService
from server.application.pinned_paths.pinned_path_store import PinnedPathStore
from server.application.tasks.task_runner import WebTaskRunner
from server.application.tasks.task_service import WebTaskService
from server.application.tasks.task_store import WebTaskStore
from server.application.web.agent_api import WebAgentApi
from server.application.web.artifact_api import WebArtifactApi
from server.application.web.command_api import WebCommandApi
from server.application.web.connection_api import WebConnectionApi
from server.application.web.job_api import WebJobApi
from server.application.web.pinned_path_api import PinnedPathApi
from server.application.web.remote_file_api import WebRemoteFileApi
from server.application.web.system_api import WebSystemInspectionApi
from server.config.config import SCRIPT_JOBS_PATH
from server.web.event_bus import WebEventBus


class ServerApplicationAssembly:
    """
    Server 应用装配层。

    职责：
    - 统一实例化应用层依赖
    - 统一处理跨 service/store 的依赖绑定
    - 统一装配 Web 子外观对象
    - 为 root facade 提供已经组装完成的依赖对象

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
        self.command_executor_factory = CommandExecutorFactory(
            server=self.server,
            remote_execution_service=self.remote_execution_service,
        )

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
            remote_execution_service=self.remote_execution_service,
            command_executor_factory=self.command_executor_factory,
        )

        self.task_service = WebTaskService(
            server=self.server,
            task_store=self.task_store,
            file_service=self.file_service,
            task_runner=self.task_runner,
        )

        self.background_job_store = BackgroundJobStore()
        self.job_catalog_service = JobCatalogService(SCRIPT_JOBS_PATH)

        self.background_job_service = BackgroundJobService(
            event_bus=self.event_bus,
            job_store=self.background_job_store,
            remote_execution_service=self.remote_execution_service,
            job_catalog_service=self.job_catalog_service,
        )

        self.pinned_path_store = PinnedPathStore()
        self.agent_builder = AgentBuilder()

        # ------------------ web sub facades / apis ------------------ #
        self.connection_api = WebConnectionApi(
            connection_service=self.connection_service,
        )

        self.command_api = WebCommandApi(
            server=self.server,
            command_executor_factory=self.command_executor_factory,
            task_service=self.task_service,
        )

        self.job_api = WebJobApi(
            command_api=self.command_api,
            background_job_service=self.background_job_service,
            job_catalog_service=self.job_catalog_service,
        )

        self.artifact_api = WebArtifactApi(
            server=self.server,
            event_bus=self.event_bus,
            artifact_service=self.artifact_service,
        )

        self.remote_file_api = WebRemoteFileApi(
            remote_file_service=self.remote_file_service,
        )

        self.pinned_path_api = PinnedPathApi(
            server=self.server,
            pinned_path_store=self.pinned_path_store,
        )

        self.agent_api = WebAgentApi(
            agent_builder=self.agent_builder,
        )

        self.system_api = WebSystemInspectionApi(
            server=self.server,
            remote_execution_service=self.remote_execution_service,
        )

        self._wire_cross_dependencies()

    def _wire_cross_dependencies(self):
        """
        统一处理跨对象依赖绑定。

        这类 wiring 原本散落在 Facade 中，
        现在收口到 assembly，避免 Facade 同时承担装配职责。
        """
        self.background_job_store.artifact_service = self.artifact_service
        self.server.command_history.artifact_service = self.artifact_service
