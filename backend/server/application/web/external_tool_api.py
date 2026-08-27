from server.application.web.external_tool_catalog_api import WebExternalToolCatalogApi
from server.application.web.external_tool_client_lifecycle_api import WebExternalToolClientLifecycleApi
from server.application.web.external_tool_param_preset_api import WebExternalToolParamPresetApi
from server.application.web.external_tool_request_context import ExternalToolRequestContextApi


class WebExternalToolApi:
    """External-tool web API root, composed from focused sub APIs."""

    def __init__(self, catalog_service, runtime_service, param_preset_store, server):
        self.request_context = ExternalToolRequestContextApi(catalog_service, server)
        self.catalog = WebExternalToolCatalogApi(catalog_service, runtime_service)
        self.client_lifecycle = WebExternalToolClientLifecycleApi(catalog_service, runtime_service)
        self.param_presets = WebExternalToolParamPresetApi(catalog_service, param_preset_store)
