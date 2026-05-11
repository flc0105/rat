from server.application.web.external_tool_catalog_api import WebExternalToolCatalogApi
from server.application.web.external_tool_client_lifecycle_api import WebExternalToolClientLifecycleApi
from server.application.web.external_tool_package_api import WebExternalToolPackageApi
from server.application.web.external_tool_request_context import ExternalToolRequestContextApi
from server.application.web.external_tool_server_instance_api import WebExternalToolServerInstanceApi


class WebExternalToolApi:
    """External-tool web API root, composed from focused sub APIs."""

    def __init__(self, catalog_service, runtime_service, server):
        self.request_context = ExternalToolRequestContextApi(catalog_service, server)
        self.catalog = WebExternalToolCatalogApi(catalog_service, runtime_service)
        self.package_runtime = WebExternalToolPackageApi(runtime_service)
        self.server_instances = WebExternalToolServerInstanceApi(catalog_service, runtime_service)
        self.client_lifecycle = WebExternalToolClientLifecycleApi(catalog_service, runtime_service)
