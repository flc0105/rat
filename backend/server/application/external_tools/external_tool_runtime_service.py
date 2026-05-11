from server.application.external_tools.external_tool_client_runtime import ExternalToolClientRuntimeMixin
from server.application.external_tools.external_tool_context_runtime import ExternalToolContextRuntimeMixin
from server.application.external_tools.external_tool_install_support import ExternalToolInstallSupportMixin
from server.application.external_tools.external_tool_package_runtime import ExternalToolPackageRuntimeMixin
from server.application.external_tools.external_tool_process_state import ExternalToolProcessStateMixin
from server.application.external_tools.external_tool_runtime_base import ExternalToolRuntimeBase
from server.application.external_tools.external_tool_server_instance_runtime import ExternalToolServerInstanceRuntimeMixin


class ExternalToolRuntimeService(
    ExternalToolClientRuntimeMixin,
    ExternalToolServerInstanceRuntimeMixin,
    ExternalToolPackageRuntimeMixin,
    ExternalToolProcessStateMixin,
    ExternalToolInstallSupportMixin,
    ExternalToolContextRuntimeMixin,
    ExternalToolRuntimeBase,
):
    """External tool runtime facade assembled from focused lifecycle services."""

    pass
