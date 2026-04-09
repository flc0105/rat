from server.application.assembly import ServerApplicationAssembly


class ServerWebService:
    """
    Server 的 Web 根外观（root facade）。

    职责：
    - 暴露装配完成的子外观对象
    - 暴露少量共享基础设施引用
    - 不再承载大批具体业务方法

    约束：
    - 不保留旧的 command/job/artifact/remote-file/agent/connection 转发方法
    - 路由层必须显式迁移到子外观
    """

    def __init__(self, server, assembly=None):
        self.server = server
        self.assembly = assembly or ServerApplicationAssembly(server)

        # ------------------ shared infrastructure ------------------ #
        self.event_bus = self.assembly.event_bus
        self.task_store = self.assembly.task_store

        # ------------------ shared services (保留给仍未拆完的模块使用) ------------------ #
        self.artifact_service = self.assembly.artifact_service
        self.file_service = self.assembly.file_service
        self.remote_execution_service = self.assembly.remote_execution_service
        self.remote_file_service = self.assembly.remote_file_service
        self.connection_service = self.assembly.connection_service
        self.command_executor_factory = self.assembly.command_executor_factory
        self.task_runner = self.assembly.task_runner
        self.task_service = self.assembly.task_service
        self.background_job_store = self.assembly.background_job_store
        self.background_job_service = self.assembly.background_job_service
        self.agent_builder = self.assembly.agent_builder

        # ------------------ sub facades / apis ------------------ #
        self.connection_api = self.assembly.connection_api
        self.command_api = self.assembly.command_api
        self.job_api = self.assembly.job_api
        self.artifact_api = self.assembly.artifact_api
        self.remote_file_api = self.assembly.remote_file_api
        self.quick_jump_api = self.assembly.quick_jump_api
        self.agent_api = self.assembly.agent_api
        self.system_api = self.assembly.system_api

    @classmethod
    def from_server(cls, server):
        """
        默认构建入口：
        - 先完成 application assembly
        - 再创建 facade
        """
        assembly = ServerApplicationAssembly(server)
        return cls(server, assembly=assembly)