from server.application.external_tools.external_tool_client_runtime import ExternalToolClientLifecycleRuntime
from server.application.external_tools.external_tool_context_runtime import ExternalToolContextRuntime
from server.application.external_tools.external_tool_install_support import ExternalToolInstallSupport
from server.application.external_tools.external_tool_package_runtime import ExternalToolPackageRuntime
from server.application.external_tools.external_tool_payload_builder import ExternalToolClientPayloadBuilder
from server.application.external_tools.external_tool_process_state import ExternalToolProcessState
from server.application.external_tools.external_tool_runtime_base import ExternalToolRuntimeBase
from server.application.external_tools.external_tool_server_instance_runtime import ExternalToolServerInstanceRuntime


class ExternalToolRuntimeService:
    """Composition root for external tool runtime services."""

    def __init__(
        self,
        catalog_service,
        command_execution_api,
        install_root_dir: str,
        runtime_root_dir: str,
        remote_execution_service=None,
    ):
        self.core = ExternalToolRuntimeBase(
            catalog_service=catalog_service,
            command_execution_api=command_execution_api,
            install_root_dir=install_root_dir,
            runtime_root_dir=runtime_root_dir,
            remote_execution_service=remote_execution_service,
        )
        self.context_runtime = ExternalToolContextRuntime(self.core)
        self.install_support = ExternalToolInstallSupport(self.core)
        self.process_state = ExternalToolProcessState(self.core)
        self.package_runtime = ExternalToolPackageRuntime(
            self.core,
            context_runtime=self.context_runtime,
            install_support=self.install_support,
            process_state=self.process_state,
        )
        self.server_instance_runtime = ExternalToolServerInstanceRuntime(
            self.core,
            context_runtime=self.context_runtime,
            install_support=self.install_support,
            process_state=self.process_state,
        )
        self.payload_builder = ExternalToolClientPayloadBuilder(
            self.core,
            context_runtime=self.context_runtime,
            install_support=self.install_support,
            process_state=self.process_state,
        )
        self.client_lifecycle_runtime = ExternalToolClientLifecycleRuntime(
            self.core,
            payload_builder=self.payload_builder,
        )
