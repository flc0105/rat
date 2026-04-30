class WebExternalToolApi:
    def __init__(self, catalog_service, runtime_service):
        self.catalog_service = catalog_service
        self.runtime_service = runtime_service

    def list_catalog(self):
        return self.catalog_service.get_catalog()

    def get_tool(self, tool_id: str):
        return self.catalog_service.get_tool(tool_id)

    def get_package_path(self, filename: str):
        return self.catalog_service.get_package_path(filename)

    def install_and_run_server(self, tool_id: str, params=None):
        return self.runtime_service.install_and_run_server(tool_id, params=params)

    def install_and_run_client(self, client_id: str, tool_id: str, params=None, tab_id: str = ''):
        return self.runtime_service.install_and_run_client(client_id, tool_id, params=params, tab_id=tab_id)
