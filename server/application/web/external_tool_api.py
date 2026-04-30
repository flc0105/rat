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

    # Server-side lifecycle
    def start_server_instance(self, tool_id: str, params=None, instance_id: str = ''):
        return self.runtime_service.start_server_instance(tool_id, params=params, instance_id=instance_id)

    def stop_server_instance(self, tool_id: str, instance_id: str, params=None):
        return self.runtime_service.stop_server_instance(tool_id, instance_id=instance_id, params=params)

    def status_server_instance(self, tool_id: str, instance_id: str):
        return self.runtime_service.status_server_instance(tool_id, instance_id=instance_id)

    def list_server_instances(self, tool_id: str):
        return self.runtime_service.list_server_instances(tool_id)

    def read_server_logs(self, tool_id: str, instance_id: str, max_bytes=None):
        return self.runtime_service.read_server_logs(tool_id, instance_id=instance_id, max_bytes=max_bytes)

    # Backward-compatible old method name.
    def install_and_run_server(self, tool_id: str, params=None):
        return self.runtime_service.install_and_run_server(tool_id, params=params)

    # Client-side lifecycle submits commands to target client.
    def start_client_instance(self, client_id: str, tool_id: str, params=None, tab_id: str = '', instance_id: str = ''):
        return self.runtime_service.start_client_instance(client_id, tool_id, params=params, tab_id=tab_id, instance_id=instance_id)

    def stop_client_instance(self, client_id: str, tool_id: str, instance_id: str, params=None, tab_id: str = ''):
        return self.runtime_service.stop_client_instance(client_id, tool_id, instance_id=instance_id, params=params, tab_id=tab_id)

    def status_client_instance(self, client_id: str, tool_id: str, instance_id: str, tab_id: str = ''):
        return self.runtime_service.status_client_instance(client_id, tool_id, instance_id=instance_id, tab_id=tab_id)

    def list_client_instances(self, client_id: str, tool_id: str, tab_id: str = ''):
        return self.runtime_service.list_client_instances(client_id, tool_id, tab_id=tab_id)

    def read_client_logs(self, client_id: str, tool_id: str, instance_id: str, max_bytes=None, tab_id: str = ''):
        return self.runtime_service.read_client_logs(client_id, tool_id, instance_id=instance_id, max_bytes=max_bytes, tab_id=tab_id)

    # Backward-compatible old method name.
    def install_and_run_client(self, client_id: str, tool_id: str, params=None, tab_id: str = ''):
        return self.runtime_service.install_and_run_client(client_id, tool_id, params=params, tab_id=tab_id)
